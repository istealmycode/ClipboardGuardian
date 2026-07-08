public struct FindingDisplayFormatter {
    public init() {}

    public func format(_ findings: [Finding]) -> String {
        guard !findings.isEmpty else {
            return "No findings detected."
        }

        return findings.map { finding in
            "[\(finding.severity.rawValue.uppercased())] \(finding.category): \(finding.message)"
        }.joined(separator: "\n")
    }
}
