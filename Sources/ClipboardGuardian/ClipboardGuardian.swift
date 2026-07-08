public enum FindingSeverity: String, CaseIterable, Sendable {
    case low
    case medium
    case high
    case critical
}

public struct Finding: Equatable, Sendable {
    public let severity: FindingSeverity
    public let category: String
    public let message: String

    public init(severity: FindingSeverity, category: String, message: String) {
        self.severity = severity
        self.category = category
        self.message = message
    }
}

public protocol DetectionRule: Sendable {
    func detect(in content: String) -> [Finding]
}

public struct Analyzer: Sendable {
    private let rules: [any DetectionRule]

    public init(rules: [any DetectionRule] = []) {
        self.rules = rules
    }

    public func analyze(_ content: String) -> [Finding] {
        rules.flatMap { $0.detect(in: content) }
    }
}
