import Foundation

public struct EncodedPayloadDetectionRule: DetectionRule {
    public init() {}

    public func detect(in content: String) -> [Finding] {
        let rules: [(pattern: String, severity: FindingSeverity, message: String)] = [
            (
                #"(?:^|\s)(?:[A-Za-z0-9+/]{4}){80,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?:\s|$)"#,
                .high,
                "A large base64 payload was detected."
            ),
            (
                #"(?:\\x[0-9a-fA-F]{2}){24,}"#,
                .critical,
                "A shellcode-like hex escaped payload was detected."
            ),
            (
                #"(?i)data:application/(?:octet-stream|x-msdownload|x-dosexec);base64,"#,
                .critical,
                "A binary file payload encoded as a data URI was detected."
            )
        ]

        for rule in rules {
            if content.range(of: rule.pattern, options: [.regularExpression]) != nil {
                return [
                    Finding(
                        severity: rule.severity,
                        category: "encoded payload",
                        message: rule.message
                    )
                ]
            }
        }

        return []
    }
}
