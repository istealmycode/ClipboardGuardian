import Foundation

public struct AWSCredentialDetectionRule: DetectionRule {
    public init() {}

    public func detect(in content: String) -> [Finding] {
        let normalized = content.trimmingCharacters(in: .whitespacesAndNewlines)

        if isAWSAccessKeyID(normalized) {
            return [
                Finding(
                    severity: .critical,
                    category: "credential",
                    message: "An AWS access key was detected."
                )
            ]
        }

        if isAWSSecretKeyAssignment(normalized) {
            return [
                Finding(
                    severity: .critical,
                    category: "credential",
                    message: "An AWS secret access key was detected."
                )
            ]
        }

        if isGenericAWSSecretShape(normalized) {
            return [
                Finding(
                    severity: .critical,
                    category: "credential",
                    message: "An AWS credential-like secret was detected."
                )
            ]
        }

        return []
    }

    private func isAWSAccessKeyID(_ content: String) -> Bool {
        let pattern = "^AKIA[0-9A-Z]{16}$"
        return content.range(of: pattern, options: [.regularExpression, .anchored]) != nil
    }

    private func isAWSSecretKeyAssignment(_ content: String) -> Bool {
        let pattern = "(?i)\\baws_secret_access_key\\s*=\\s*.+"
        return content.range(of: pattern, options: [.regularExpression]) != nil
    }

    private func isGenericAWSSecretShape(_ content: String) -> Bool {
        let pattern = "^(?=.*[A-Za-z])(?=.*[0-9]).{20,}$"
        let hasSlashOrPlus = content.contains("/") || content.contains("+") || content.contains("=")
        guard hasSlashOrPlus else { return false }
        return content.range(of: pattern, options: [.regularExpression]) != nil
    }
}
