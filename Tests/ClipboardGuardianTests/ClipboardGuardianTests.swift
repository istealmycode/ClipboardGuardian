import XCTest
@testable import ClipboardGuardian

final class ClipboardGuardianTests: XCTestCase {
    static let allTests = [
        ("testAnalyzerWithNoRulesReturnsNoFindings", testAnalyzerWithNoRulesReturnsNoFindings),
        ("testAnalyzerCanUseMockDetectionRule", testAnalyzerCanUseMockDetectionRule),
        ("testSeverityAndMessagesArePreserved", testSeverityAndMessagesArePreserved),
        ("testAnalyzerDetectsPrivateKeyContent", testAnalyzerDetectsPrivateKeyContent),
        ("testAnalyzerDetectsPrivateKeyWithLooseBoundaryFormatting", testAnalyzerDetectsPrivateKeyWithLooseBoundaryFormatting),
        ("testAnalyzerDoesNotFlagNormalPrivateKeySentence", testAnalyzerDoesNotFlagNormalPrivateKeySentence),
        ("testAnalyzerDetectsAWSAccessKeyID", testAnalyzerDetectsAWSAccessKeyID),
        ("testAnalyzerDetectsAWSSecretAccessKeyFormat", testAnalyzerDetectsAWSSecretAccessKeyFormat),
        ("testAnalyzerDoesNotFlagNormalAWSText", testAnalyzerDoesNotFlagNormalAWSText),
        ("testAnalyzerDoesNotFlagRandomIdentifier", testAnalyzerDoesNotFlagRandomIdentifier),
        ("testAnalyzerDetectsGenericAWSSecretShape", testAnalyzerDetectsGenericAWSSecretShape),
        ("testAnalyzerDetectsGitHubToken", testAnalyzerDetectsGitHubToken),
        ("testAnalyzerDetectsGenericCredential", testAnalyzerDetectsGenericCredential),
        ("testAnalyzerDetectsJWT", testAnalyzerDetectsJWT),
        ("testAnalyzerDetectsEncodedPayload", testAnalyzerDetectsEncodedPayload),
        ("testAnalyzerDetectsMaliciousJavaScript", testAnalyzerDetectsMaliciousJavaScript),
        ("testDefaultDetectionRulesIncludeExpandedLocalRules", testDefaultDetectionRulesIncludeExpandedLocalRules)
    ]

    func testAnalyzerWithNoRulesReturnsNoFindings() {
        let analyzer = Analyzer()

        let findings = analyzer.analyze("safe clipboard content")

        XCTAssertTrue(findings.isEmpty)
    }

    func testAnalyzerCanUseMockDetectionRule() {
        struct MockDetectionRule: DetectionRule {
            func detect(in content: String) -> [Finding] {
                guard content.contains("secret") else {
                    return []
                }

                return [
                    Finding(
                        severity: .high,
                        category: "mock",
                        message: "Mock rule detected a secret"
                    )
                ]
            }
        }

        let analyzer = Analyzer(rules: [MockDetectionRule()])

        let findings = analyzer.analyze("contains secret")

        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings.first?.severity, .high)
        XCTAssertEqual(findings.first?.category, "mock")
    }

    func testSeverityAndMessagesArePreserved() {
        let finding = Finding(
            severity: .critical,
            category: "credential",
            message: "A credential-like value was found"
        )

        XCTAssertEqual(finding.severity, .critical)
        XCTAssertEqual(finding.category, "credential")
        XCTAssertEqual(finding.message, "A credential-like value was found")
    }

    func testAnalyzerDetectsPrivateKeyContent() {
        let analyzer = Analyzer(rules: [PrivateKeyDetectionRule()])
        let content = """
        -----BEGIN PRIVATE KEY-----
        some fake key data
        -----END PRIVATE KEY-----
        """

        let findings = analyzer.analyze(content)

        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings.first?.category, "private key")
        XCTAssertEqual(findings.first?.severity, .critical)
        XCTAssertTrue(findings.first?.message.contains("private key") == true)
    }

    func testAnalyzerDetectsPrivateKeyWithLooseBoundaryFormatting() {
        let analyzer = Analyzer(rules: [PrivateKeyDetectionRule()])
        let content = """
        --BEGIN PRIVATE KEY-
        some fake key data
        -END PRIVATE KEY--
        """

        let findings = analyzer.analyze(content)

        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings.first?.category, "private key")
    }

    func testAnalyzerDoesNotFlagNormalPrivateKeySentence() {
        let analyzer = Analyzer(rules: [PrivateKeyDetectionRule()])
        let content = "This sentence mentions a private key in a normal conversation."

        let findings = analyzer.analyze(content)

        XCTAssertTrue(findings.isEmpty)
    }

    func testAnalyzerDetectsAWSAccessKeyID() {
        let analyzer = Analyzer(rules: [AWSCredentialDetectionRule()])
        let content = "AKIAIOSFODNN7EXAMPLE"

        let findings = analyzer.analyze(content)

        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings.first?.category, "credential")
        XCTAssertEqual(findings.first?.severity, .critical)
        XCTAssertTrue(findings.first?.message.contains("AWS access key") == true)
    }

    func testAnalyzerDetectsAWSSecretAccessKeyFormat() {
        let analyzer = Analyzer(rules: [AWSCredentialDetectionRule()])
        let content = "aws_secret_access_key = exampleSecretValue"

        let findings = analyzer.analyze(content)

        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings.first?.category, "credential")
        XCTAssertEqual(findings.first?.severity, .critical)
        XCTAssertTrue(findings.first?.message.contains("AWS") == true)
    }

    func testAnalyzerDoesNotFlagNormalAWSText() {
        let analyzer = Analyzer(rules: [AWSCredentialDetectionRule()])
        let content = "This text mentions AWS, access, and key in a normal sentence."

        let findings = analyzer.analyze(content)

        XCTAssertTrue(findings.isEmpty)
    }

    func testAnalyzerDoesNotFlagRandomIdentifier() {
        let analyzer = Analyzer(rules: [AWSCredentialDetectionRule()])
        let content = "randomIdentifier123"

        let findings = analyzer.analyze(content)

        XCTAssertTrue(findings.isEmpty)
    }

    func testFindingDisplayFormatterFormatsFindingsForUI() {
        let formatter = FindingDisplayFormatter()
        let finding = Finding(
            severity: .critical,
            category: "credential",
            message: "An AWS access key was detected."
        )

        let output = formatter.format([finding])

        XCTAssertEqual(output, "[CRITICAL] credential: An AWS access key was detected.")
    }

    func testAnalyzerDetectsGenericAWSSecretShape() {
        let analyzer = Analyzer(rules: [AWSCredentialDetectionRule()])
        let content = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

        let findings = analyzer.analyze(content)

        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings.first?.category, "credential")
        XCTAssertEqual(findings.first?.severity, .critical)
        XCTAssertTrue(findings.first?.message.contains("AWS") == true)
    }

    func testAnalyzerDetectsGitHubToken() {
        let analyzer = Analyzer(rules: [GitHubTokenDetectionRule()])
        let content = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD"

        let findings = analyzer.analyze(content)

        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings.first?.category, "credential")
        XCTAssertEqual(findings.first?.severity, .critical)
        XCTAssertTrue(findings.first?.message.contains("GitHub") == true)
    }

    func testAnalyzerDetectsGenericCredential() {
        let analyzer = Analyzer(rules: [GenericCredentialDetectionRule()])
        let content = "sk" + "_live_" + "1234567890abcdefghijklmnopqrst"

        let findings = analyzer.analyze(content)

        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings.first?.category, "credential")
        XCTAssertEqual(findings.first?.severity, .critical)
    }

    func testAnalyzerDetectsJWT() {
        let analyzer = Analyzer(rules: [JWTDetectionRule()])
        let content = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

        let findings = analyzer.analyze(content)

        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings.first?.category, "credential")
        XCTAssertEqual(findings.first?.severity, .high)
    }

    func testAnalyzerDetectsEncodedPayload() {
        let analyzer = Analyzer(rules: [EncodedPayloadDetectionRule()])
        let content = String(repeating: "QUJD", count: 120)

        let findings = analyzer.analyze(content)

        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings.first?.category, "encoded payload")
        XCTAssertEqual(findings.first?.severity, .high)
    }

    func testAnalyzerDetectsMaliciousJavaScript() {
        let analyzer = Analyzer(rules: [MaliciousJavaScriptDetectionRule()])
        let content = "eval(atob('YWxlcnQoMSk='));"

        let findings = analyzer.analyze(content)

        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings.first?.category, "malicious script")
        XCTAssertEqual(findings.first?.severity, .high)
    }

    func testDefaultDetectionRulesIncludeExpandedLocalRules() {
        let analyzer = Analyzer(rules: defaultDetectionRules())
        let findings = analyzer.analyze("eval(atob('YWxlcnQoMSk='));")

        XCTAssertFalse(findings.isEmpty)
        XCTAssertTrue(findings.contains(where: { $0.category == "malicious script" }))
    }
}
