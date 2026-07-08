import Foundation
import ClipboardGuardian

@main
struct ClipboardGuardianCLI {
    static func main() {
        let inputText: String

        if CommandLine.arguments.count > 1 {
            inputText = CommandLine.arguments.dropFirst().joined(separator: " ")
        } else {
            let stdinData = FileHandle.standardInput.readDataToEndOfFile()
            inputText = String(data: stdinData, encoding: .utf8) ?? ""
        }

        let analyzer = Analyzer(rules: [
            PrivateKeyDetectionRule(),
            AWSCredentialDetectionRule()
        ])

        let findings = analyzer.analyze(inputText)

        if findings.isEmpty {
            print("No findings detected.")
            return
        }

        for finding in findings {
            print("[\(finding.severity.rawValue.uppercased())] \(finding.category): \(finding.message)")
        }
    }
}
